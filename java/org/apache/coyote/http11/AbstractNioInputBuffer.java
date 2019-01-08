/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http11;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.coyote.Request;
import org.apache.tomcat.util.buf.MessageBytes;

public abstract class AbstractNioInputBuffer<S> extends AbstractInputBuffer<S> {

    // -------------------------------------------------------------- Constants

    enum HeaderParseStatus {
        DONE, HAVE_MORE_HEADERS, NEED_MORE_DATA
    }

    enum HeaderParsePosition {
        /**
         * Start of a new header. A CRLF here means that there are no more
         * headers. Any other character starts a header name.
         */
        HEADER_START,
        /**
         * Reading a header name. All characters of header are HTTP_TOKEN_CHAR.
         * Header name is followed by ':'. No whitespace is allowed.<br>
         * Any non-HTTP_TOKEN_CHAR (this includes any whitespace) encountered
         * before ':' will result in the whole line being ignored.
         */
        HEADER_NAME,
        /**
         * Skipping whitespace before text of header value starts, either on the
         * first line of header value (just after ':') or on subsequent lines
         * when it is known that subsequent line starts with SP or HT.
         */
        HEADER_VALUE_START,
        /**
         * Reading the header value. We are inside the value. Either on the
         * first line or on any subsequent line. We come into this state from
         * HEADER_VALUE_START after the first non-SP/non-HT byte is encountered
         * on the line.
         */
        HEADER_VALUE,
        /**
         * Before reading a new line of a header. Once the next byte is peeked,
         * the state changes without advancing our position. The state becomes
         * either HEADER_VALUE_START (if that first byte is SP or HT), or
         * HEADER_START (otherwise).
         */
        HEADER_MULTI_LINE,//用来判定是否多行请求头
        /**
         * Reading all bytes until the next CRLF. The line is being ignored.
         */
        HEADER_SKIPLINE
    }

    // ----------------------------------------------------------- Constructors


    /**
     * Alternate constructor.
     */
    public AbstractNioInputBuffer(Request request, int headerBufferSize) {

        this.request = request;
        headers = request.getMimeHeaders();

        this.headerBufferSize = headerBufferSize;

        filterLibrary = new InputFilter[0];
        activeFilters = new InputFilter[0];
        lastActiveFilter = -1;

        parsingHeader = true;
        parsingRequestLine = true;
        parsingRequestLinePhase = 0;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        headerParsePos = HeaderParsePosition.HEADER_START;
        headerData.recycle();
        swallowInput = true;

    }

    /**
     * Parsing state - used for non blocking parsing so that
     * when more data arrives, we can pick up where we left off.
     */
    private boolean parsingRequestLine;//标记是否需要解析请求行，在构造函数中初始化为true
    private int parsingRequestLinePhase = 0;
    private boolean parsingRequestLineEol = false;
    private int parsingRequestLineStart = 0;
    private int parsingRequestLineQPos = -1;
    private HeaderParsePosition headerParsePos;

    /**
     * 最大byte数：请求行+请求头+空行
     * Maximum allowed size of the HTTP request line plus headers plus any
     * leading blank lines.
     */
    protected final int headerBufferSize;

    /**
     * NioChannel的缓冲区长度
     * Known size of the NioChannel read buffer.
     */
    protected int socketReadBufferSize;

    // --------------------------------------------------------- Public Methods

    /**
     * Recycle the input buffer. This should be called when closing the
     * connection.
     */
    @Override
    public void recycle() {
        super.recycle();
        headerParsePos = HeaderParsePosition.HEADER_START;
        parsingRequestLine = true;
        parsingRequestLinePhase = 0;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        headerData.recycle();
    }


    /**
     * 当前的请求解析完毕
     * 注意：当前请求的所有字节都解析完毕。这个方法仅仅重置了所有的标志，以便解析下一个http请求
     * End processing of current HTTP request.
     * Note: All bytes of the current request should have been already
     * consumed. This method only resets all the pointers so that we are ready
     * to parse the next HTTP request.
     */
    @Override
    public void nextRequest() {
        super.nextRequest();
        headerParsePos = HeaderParsePosition.HEADER_START;
        parsingRequestLine = true;
        parsingRequestLinePhase = 0;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        headerData.recycle();
    }

    /**
     * Read the request line. This function is meant to be used during the
     * HTTP request header parsing. Do NOT attempt to read the request body
     * using it.
     *
     * @throws IOException If an exception occurs during the underlying socket
     * read operations, or if the given buffer is not big enough to accommodate
     * the whole line.
     * @return true if data is properly fed; false if no data is available
     * immediately and thread should be freed
     */
    @Override
    public boolean parseRequestLine(boolean useAvailableDataOnly)
        throws IOException {

        //check state
        if ( !parsingRequestLine ) return true;//检车请求行解析状态，保证只解析一次
        //
        // Skipping blank lines
        //parsingRequestLinePhase用来标记：正在解析请求行的段落数，让pos一只跳过无效数据
        if ( parsingRequestLinePhase < 2 ) {
            byte chr = 0;
            do {

                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (useAvailableDataOnly) {
                        return false;
                    }
                    // Do a simple read with a short timeout 读取数据
                    if (!fill(false)) {
                        //未读取到数据直接返回失败
                        // A read is pending, so no longer in initial state
                        parsingRequestLinePhase = 1;
                        return false;
                    }
                }
                // Set the start time once we start reading data (even if it is
                // just skipping blank lines)
                if (request.getStartTime() < 0) {
                    request.setStartTime(System.currentTimeMillis());//标记开始解析请求的时间
                }
                chr = buf[pos++];//获取读取到的第一个字节
            } while ((chr == Constants.CR) || (chr == Constants.LF));//跳过回车换行
            pos--;
            //此时，pos指向的数据已经指向第一个有效数据了，后面可以开始进行解析的工作了，有可能已经从socket中读取了多次了

            parsingRequestLineStart = pos;
            parsingRequestLinePhase = 2;
            if (getLog().isDebugEnabled()) {
                getLog().debug("Received ["
                        + new String(buf, pos, lastValid - pos,
                                StandardCharsets.ISO_8859_1)
                        + "]");
            }
        }
        //pos已经移动到第一个有效数据
        if ( parsingRequestLinePhase == 2 ) {
            //
            // 读取请求方法
            // Reading the method name
            // Method name is a token
            //
            boolean space = false;
            while (!space) {
                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (!fill(false)) //request line parsing 继续填充数据
                        return false;
                }
                // Spec says method name is a token followed by a single SP but
                // also be tolerant of multiple SP and/or HT.
                if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
                    space = true;
                    request.method().setBytes(buf, parsingRequestLineStart, pos - parsingRequestLineStart);
                } else if (!HTTP_TOKEN_CHAR[buf[pos]]) {
                    throw new IllegalArgumentException(sm.getString("iib.invalidmethod"));
                }
                pos++;//pos后移，直到读取到空格
            }
            parsingRequestLinePhase = 3;
        }
        if ( parsingRequestLinePhase == 3 ) {
            //跳过更多的空格，制表符
            // Spec says single SP but also be tolerant of multiple SP and/or HT
            boolean space = true;
            while (space) {
                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (!fill(false)) //request line parsing
                        return false;
                }
                if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
                    pos++;
                } else {
                    space = false;
                }
            }
            parsingRequestLineStart = pos;
            parsingRequestLinePhase = 4;
        }
        if (parsingRequestLinePhase == 4) {
            // Mark the current buffer position

            int end = 0;
            //
            // Reading the URI
            // 读取URI
            //
            boolean space = false;
            while (!space) {
                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (!fill(false)) //request line parsing
                        return false;
                }
                if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
                    space = true;
                    end = pos;
                } else if ((buf[pos] == Constants.CR)
                           || (buf[pos] == Constants.LF)) {
                    // HTTP/0.9 style request
                    parsingRequestLineEol = true;
                    space = true;
                    end = pos;
                } else if ((buf[pos] == Constants.QUESTION)
                           && (parsingRequestLineQPos == -1)) {
                    parsingRequestLineQPos = pos;
                }
                pos++;
            }
            if (parsingRequestLineQPos >= 0) {
                request.queryString().setBytes(buf, parsingRequestLineQPos + 1,
                                               end - parsingRequestLineQPos - 1);
                request.requestURI().setBytes(buf, parsingRequestLineStart, parsingRequestLineQPos - parsingRequestLineStart);
            } else {
                request.requestURI().setBytes(buf, parsingRequestLineStart, end - parsingRequestLineStart);
            }
            parsingRequestLinePhase = 5;
        }
        //去除更多的空格和制表符
        if ( parsingRequestLinePhase == 5 ) {
            // Spec says single SP but also be tolerant of multiple and/or HT
            boolean space = true;
            while (space) {
                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (!fill(false)) //request line parsing
                        return false;
                }
                if (buf[pos] == Constants.SP || buf[pos] == Constants.HT) {
                    pos++;
                } else {
                    space = false;
                }
            }
            parsingRequestLineStart = pos;
            parsingRequestLinePhase = 6;

            // Mark the current buffer position
            end = 0;
        }
        // 解析请求协议
        if (parsingRequestLinePhase == 6) {
            //
            // Reading the protocol
            // Protocol is always US-ASCII
            //
            while (!parsingRequestLineEol) {
                // Read new bytes if needed
                if (pos >= lastValid) {
                    if (!fill(false)) //request line parsing
                        return false;
                }

                if (buf[pos] == Constants.CR) {
                    end = pos;
                } else if (buf[pos] == Constants.LF) {
                    if (end == 0)
                        end = pos;
                    parsingRequestLineEol = true;
                }
                pos++;
            }

            if ( (end - parsingRequestLineStart) > 0) {
                //把数据单独抠出来放到MessageBytes中
                request.protocol().setBytes(buf, parsingRequestLineStart, end - parsingRequestLineStart);
            } else {
                request.protocol().setString("");
            }
            parsingRequestLine = false;
            parsingRequestLinePhase = 0;
            parsingRequestLineEol = false;
            parsingRequestLineStart = 0;
            return true;
        }
        throw new IllegalStateException("Invalid request line parse phase:"+parsingRequestLinePhase);
    }

    protected void expand(int newsize) {
        if ( newsize > buf.length ) {//先检验是否需要扩容
            if (parsingHeader) {
                throw new IllegalArgumentException(
                        sm.getString("iib.requestheadertoolarge.error"));
            }
            // Should not happen
            getLog().warn("Expanding buffer size. Old size: " + buf.length
                    + ", new size: " + newsize, new Exception());
            byte[] tmp = new byte[newsize];
            System.arraycopy(buf,0,tmp,0,buf.length);
            buf = tmp;
        }
    }

    /**
     * Parse the HTTP headers.
     */
    @Override
    public boolean parseHeaders()
        throws IOException {
        if (!parsingHeader) {
            throw new IllegalStateException(
                    sm.getString("iib.parseheaders.ise.error"));
        }

        HeaderParseStatus status = HeaderParseStatus.HAVE_MORE_HEADERS;

        do {
            status = parseHeader();
            // Checking that
            // (1) Headers plus request line size does not exceed its limit
            // (2) There are enough bytes to avoid expanding the buffer when
            // reading body
            // Technically, (2) is technical limitation, (1) is logical
            // limitation to enforce the meaning of headerBufferSize
            // From the way how buf is allocated and how blank lines are being
            // read, it should be enough to check (1) only.
            if (pos > headerBufferSize
                    || buf.length - pos < socketReadBufferSize) {
                throw new IllegalArgumentException(
                        sm.getString("iib.requestheadertoolarge.error"));
            }
        } while ( status == HeaderParseStatus.HAVE_MORE_HEADERS );
        if (status == HeaderParseStatus.DONE) {
            parsingHeader = false;//解析完毕，标记不需要再解析请求头了
            end = pos;//记录请求头的结束
            return true;
        } else {
            return false;
        }
    }

    /**
     * Parse an HTTP header.
     *
     * @return false after reading a blank line (which indicates that the
     * HTTP header parsing is done
     */
    private HeaderParseStatus parseHeader()
        throws IOException {

        //
        // Check for blank line
        //

        byte chr = 0;
        //headerParsePos记录当前读取的请求头的位置 默认是HEADER_START
        while (headerParsePos == HeaderParsePosition.HEADER_START) {

            // Read new bytes if needed
            //读取更多的数据
            if (pos >= lastValid) {
                if (!fill(false)) {//parse header
                    headerParsePos = HeaderParsePosition.HEADER_START;
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            chr = buf[pos];


            if (chr == Constants.CR) {
                //忽略回车符
                // Skip
            } else if (chr == Constants.LF) {
                pos++;
                //以换行符'\n'行开头，作为请求头读取的结束
                return HeaderParseStatus.DONE;
            } else {
                break;
                //不是回车换行，证明可以开始读取请求头的name了
            }

            pos++;

        }

        if ( headerParsePos == HeaderParsePosition.HEADER_START ) {
            // Mark the current buffer position
            headerData.start = pos;
            headerParsePos = HeaderParsePosition.HEADER_NAME;//标记当前解析的状态为HEADER_NAME
        }

        //
        // Reading the header name 解析请求头的name
        // Header name is always US-ASCII
        //

        while (headerParsePos == HeaderParsePosition.HEADER_NAME) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill(false)) { //parse header
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            chr = buf[pos];
            if (chr == Constants.COLON) {
                //如果是冒号':'，表示key已经读取完成，已经开始解析请求头的值
                headerParsePos = HeaderParsePosition.HEADER_VALUE_START;
                //使用未转化的字节数组创建新的header
                headerData.headerValue = headers.addValue(buf, headerData.start, pos - headerData.start);
                pos++;
                // Mark the current buffer position
                headerData.start = pos;//记录headerValue的开始
                headerData.lastSignificantChar = pos;//记录headerValue的当前位置
                break;
            } else if (chr < 0 || !HTTP_TOKEN_CHAR[chr]) {
                // If a non-token header is detected, skip the line and
                // ignore the header
                headerData.lastSignificantChar = pos;
                return skipLine();
            }

            // chr is next byte of header name. Convert to lowercase.
            if ((chr >= Constants.A) && (chr <= Constants.Z)) {
                buf[pos] = (byte) (chr - Constants.LC_OFFSET);
            }
            pos++;
        }

        // Skip the line and ignore the header
        if (headerParsePos == HeaderParsePosition.HEADER_SKIPLINE) {
            return skipLine();
        }

        //
        // Reading the header value (which can be spanned over multiple lines)
        //
        // headerParsePos 作为是否继续读取的标记
        while (headerParsePos == HeaderParsePosition.HEADER_VALUE_START ||
               headerParsePos == HeaderParsePosition.HEADER_VALUE ||
               headerParsePos == HeaderParsePosition.HEADER_MULTI_LINE) {

            if ( headerParsePos == HeaderParsePosition.HEADER_VALUE_START ) {
                // Skipping spaces
                while (true) {
                    // Read new bytes if needed
                    if (pos >= lastValid) {
                        if (!fill(false)) {//parse header
                            //HEADER_VALUE_START
                            return HeaderParseStatus.NEED_MORE_DATA;
                        }
                    }

                    chr = buf[pos];
                    if (chr == Constants.SP || chr == Constants.HT) {
                        pos++;//跳过空格和制表符
                    } else {
                        headerParsePos = HeaderParsePosition.HEADER_VALUE;
                        break;
                    }
                }
            }
            //开始读取headValue
            if ( headerParsePos == HeaderParsePosition.HEADER_VALUE ) {

                // Reading bytes until the end of the line 读取一整行的数据
                boolean eol = false;
                while (!eol) {

                    // Read new bytes if needed
                    if (pos >= lastValid) {
                        if (!fill(false)) {//parse header
                            //HEADER_VALUE
                            return HeaderParseStatus.NEED_MORE_DATA;
                        }
                    }

                    chr = buf[pos];
                    if (chr == Constants.CR) {
                        // Skip  跳过回车
                    } else if (chr == Constants.LF) {
                        eol = true;//换行：作为结束标志
                    } else if (chr == Constants.SP || chr == Constants.HT) {
                        buf[headerData.realPos] = chr;//把数据缓存的到buf
                        headerData.realPos++;//记录真实读取过程的位置
                    } else {
                        buf[headerData.realPos] = chr;
                        headerData.realPos++;
                        headerData.lastSignificantChar = headerData.realPos;//只有非空格和制表符才统计
                    }

                    pos++;
                }

                // Ignore whitespaces at the end of the line
                headerData.realPos = headerData.lastSignificantChar;//读取一段headValue完毕后，把realPos指针移回真实数据的位置

                // Checking the first character of the new line. If the character
                // is a LWS, then it's a multiline header
                headerParsePos = HeaderParsePosition.HEADER_MULTI_LINE;//标记：需要读取下一行第一个字符，判定当前是否是多行请求头
            }
            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill(false)) {//parse header
                    //HEADER_MULTI_LINE
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            /**
             * 引用https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html的一句话
             * Header fields can be extended over multiple lines by preceding each extra line with at least one SP or HT.
             * 请求头可以通过在多余行的前面放置至少一个空格或制表符，从而扩展多行。
             */

            chr = buf[pos];//读取下一行第一个字符
            if ( headerParsePos == HeaderParsePosition.HEADER_MULTI_LINE ) {
                //在读取完成一行之后，继续校验后面的数据是否还属于当前的headerName
                if ( (chr != Constants.SP) && (chr != Constants.HT)) {
                    //遇到非空格和非制表符，则表示无更多行headerValue需要读取，跳出headerValue读取循环
                    headerParsePos = HeaderParsePosition.HEADER_START;
                    break;
                } else {
                    //下一行的开头是空格或者制表符：是多行数据
                    // Copying one extra space in the buffer (since there must
                    // be at least one space inserted between the lines)
                    buf[headerData.realPos] = chr;//拷贝1byte的数据到buf，准备读取下一行数据
                    headerData.realPos++;
                    headerParsePos = HeaderParsePosition.HEADER_VALUE_START;//继续读取headerValue
                }
            }
        }
        // Set the header value 把具体的缓冲区的值设置进去
        headerData.headerValue.setBytes(buf, headerData.start,
                headerData.lastSignificantChar - headerData.start);
        headerData.recycle();
        return HeaderParseStatus.HAVE_MORE_HEADERS;
    }

    public int getParsingRequestLinePhase() {
        return parsingRequestLinePhase;
    }

    private HeaderParseStatus skipLine() throws IOException {
        headerParsePos = HeaderParsePosition.HEADER_SKIPLINE;
        boolean eol = false;

        // Reading bytes until the end of the line
        while (!eol) {

            // Read new bytes if needed
            if (pos >= lastValid) {
                if (!fill(false)) {
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            if (buf[pos] == Constants.CR) {
                // Skip
            } else if (buf[pos] == Constants.LF) {
                eol = true;
            } else {
                headerData.lastSignificantChar = pos;
            }

            pos++;
        }
        if (getLog().isDebugEnabled()) {
            getLog().debug(sm.getString("iib.invalidheader", new String(buf,
                    headerData.start,
                    headerData.lastSignificantChar - headerData.start + 1,
                    StandardCharsets.ISO_8859_1)));
        }

        headerParsePos = HeaderParsePosition.HEADER_START;
        return HeaderParseStatus.HAVE_MORE_HEADERS;
    }

    private final HeaderParseData headerData = new HeaderParseData();//记录当前正在解析的请求头信息：（请求方法，请求头，要跳过的请求行）
    public static class HeaderParseData {
        /**
         * When parsing header name: first character of the header.<br>
         * When skipping broken header line: first character of the header.<br>
         * When parsing header value: first character after ':'.
         */
        int start = 0;
        /**
         * When parsing header name: not used (stays as 0).<br>
         * When skipping broken header line: not used (stays as 0).<br>
         * When parsing header value: starts as the first character after ':'.
         * Then is increased as far as more bytes of the header are harvested.
         * Bytes from buf[pos] are copied to buf[realPos]. Thus the string from
         * [start] to [realPos-1] is the prepared value of the header, with
         * whitespaces removed as needed.<br>
         */
        int realPos = 0;//读取headValue时使用：记录读取过程中的真实位置（遇到空格和制表符需要统计）
        /**
         * When parsing header name: not used (stays as 0).<br>
         * When skipping broken header line: last non-CR/non-LF character.<br>
         * When parsing header value: position after the last not-LWS character.<br>
         */
        int lastSignificantChar = 0;//读取headValue时使用：记录最后一次读取到的真实数据的位置（遇到空格和制表符不统计）
        /**
         * MB that will store the value of the header. It is null while parsing
         * header name and is created after the name has been parsed.
         */
        MessageBytes headerValue = null;
        public void recycle() {
            start = 0;
            realPos = 0;
            lastSignificantChar = 0;
            headerValue = null;
        }
    }

}
