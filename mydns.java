import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class mydns {
    // create DNS query message
    public static byte[] createQuery(int id, String domainName) {
        // Header section
        System.out.println("Creating query --====-=--=-==-=--=-=-=-=-=-=-=-==-=-=-=-=-");
        ByteBuffer query = ByteBuffer.allocate(1024);
        query.order(ByteOrder.BIG_ENDIAN);

        // Query header [RFC 4.1.1. Header section format]
        //                                 1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |  # of name, typefields for query QDCOUNT      |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |    ANCOUNT # of resource records              |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | NSCOUNT # of records for authoritative servers|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |       ARCOUNT additional info                 |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //QR = Query or response
        //AA = authoritative answer - 0 indicates authoritative server
        //RCODE = successful or failed response

        query.putShort((short)id);    // ID
        query.putShort((short)0);     // Flags
        query.putShort((short)1);     // QDCOUNT
        query.putShort((short)0);     // ANCOUNT
        query.putShort((short)0);     // NSCOUNT
        query.putShort((short)0);     // ARCOUNT

        // Question section [RFC 4.1.2. Question section format]
        //                             1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                                               |
        // /          QNAME domain name                    /
        // /                                               /
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |         QTYPE   host or mail                  |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QCLASS                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        // Split domain name into labels
        //split by .
        String[] labels = domainName.split("\\."); //cs.fiu.edu
        System.out.println("labels: ");
        for(String s: labels) {System.out.println(s);};
        for (String label : labels) {
            query.put((byte)label.length()); // length byte
            query.put(label.getBytes(StandardCharsets.UTF_8));  // label bytes
        }
        query.put((byte)0);  // zero length byte as end of qname
        query.putShort((short)1);  // QTYPE
        query.putShort((short)1);  // QCLASS
        
        return query.array();
    }

    static class NumberResult {
        long number;
        int nextIndex;
        
        NumberResult(long number, int nextIndex) {
            this.number = number;
            this.nextIndex = nextIndex;
        }
    }

    static class NameResult {
        String name;
        int nextIndex;
        
        NameResult(String name, int nextIndex) {
            this.name = name;
            this.nextIndex = nextIndex;
        }
    }

    // parse byte_length bytes from index as unsigned integer
    public static NumberResult parseUnsignedInt(int index, int byteLength, byte[] response) {
        ByteBuffer buffer = ByteBuffer.wrap(response, index, byteLength); //stream bytes into a buffer
        buffer.order(ByteOrder.BIG_ENDIAN);
        
        long num;
        switch (byteLength) {
            case 1: num = buffer.get() & 0xFF; break; //this is a byte - AND buffer with 0b11111111
            case 2: num = buffer.getShort() & 0xFFFF; break; //this is a short - AND buffer with 0b1111111111111111
            case 4: num = buffer.getInt() & 0xFFFFFFFF; break;
            default: throw new IllegalArgumentException("Unsupported byte length");
        }
        return new NumberResult(num, index + byteLength);
    }

    // parse name as label series from index
    public static NameResult parseName(int index, byte[] response) {
        StringBuilder name = new StringBuilder();
        int end = 0;
        boolean loop = true;
        int currentIndex = index;

        while (loop) {
            int labelLength = response[currentIndex] & 0xFF; //and curr number with 255
            //returns the current byte

            if (labelLength == 0) {
                end = currentIndex + 1;
                loop = false;
            }
            // pointer
            else if (labelLength >= 0xC0) { // 11000000 in binary, 192 in decimal
                int offset = ((response[currentIndex] & 0x3F) << 8) + 
                           (response[currentIndex + 1] & 0xFF);
                end = currentIndex + 2;
                NameResult prevName = parseName(offset, response); //parse the next byte (?)
                name.append(prevName.name);
                break;
            }
            // label
            else {
                currentIndex++;
                String label = new String(response, currentIndex, labelLength, 
                                       StandardCharsets.UTF_8); //decipher bytes into string
                name.append(label).append(".");
                currentIndex += labelLength;
            }
        }

        String result = name.toString();
        if (result.endsWith(".")) {
            result = result.substring(0, result.length() - 1);
        }

        return new NameResult(result, end);
    }

    public static NameResult parseAddress(int index, byte[] response) {
        //NameResult ip = null;
        byte[] ipBytes = new byte[4];

        int currentIndex = index;
        int labelLength = 0;
        for(int i = 0; i < ipBytes.length; i++, currentIndex++) { //doesn't parse IPv6
            labelLength = response[currentIndex] & 0xFF;
            //System.out.println("labellength " + labelLength);
            ipBytes[i] = (byte) labelLength;
        }

        try {
            InetAddress ipInet = InetAddress.getByAddress(ipBytes);
            String hostIp = ipInet.getHostAddress();
            System.out.println("Found host ip: " + hostIp);
            return new NameResult(hostIp, currentIndex);
        } catch (UnknownHostException exp) {
            System.out.println("Unknown IP for bytes: ");
            for(byte b: ipBytes)
                System.out.println(b);
        }
        return new NameResult("Not found", currentIndex);
    }

    // parse DNS response
    public static NameResult[] parseResponse(byte[] response) {
        System.out.println("----- parse response -----");
        int index = 0;

        System.out.println("Header section [RFC 4.1.1. Header section format]");
        // Header section [RFC 4.1.1. Header section format]
        //                                 1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    QDCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ANCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    NSCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ARCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        NumberResult result = parseUnsignedInt(index, 2, response);
        System.out.println("ID: " + result.number);
        index = result.nextIndex;

        index += 2; // skip flags

        result = parseUnsignedInt(index, 2, response);
        System.out.println("QDCOUNT: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("ANCOUNT: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("NSCOUNT: " + result.number);
        long nsCount = result.number;
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("ARCOUNT: " + result.number);
        long arCount = result.number;
        index = result.nextIndex;

        System.out.println("Question section [RFC 4.1.2. Question section format]");
        // Question section [RFC 4.1.2. Question section format]
        //                                 1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                                               |
        // /                     QNAME                     /
        // /                                               /
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QTYPE                     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     QCLASS                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        NameResult nameResult = parseName(index, response);
        System.out.println("QNAME: " + nameResult.name);
        index = nameResult.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("QTYPE: " + result.number);
        index = result.nextIndex;

        result = parseUnsignedInt(index, 2, response);
        System.out.println("QCLASS: " + result.number);
        index = result.nextIndex;


        System.out.println("Resource Record section [RFC 4.1.2. RR section format]");
        //RESOURCE RECORD SECTION
        //FORMAT

        /* 
         * Name
         * Type
         * Class
         * TTL
         * RDLength
         * RData
         * 
         */

        // NameResult rrResult = parseName(index, response);
        // System.out.println("RR NAME: " + rrResult.name);
        // index = rrResult.nextIndex;

        // //NameResult rrResultName = parseName(index, response);
        // result = parseUnsignedInt(index, 2, response);
        // System.out.println("RR Type: " + result.number);
        // index = result.nextIndex;

        //type = 2 bytes
        //class = 2 bytes
        //TTL = 4 bytes

        for(int count = 0; count < nsCount; count++) {
            for(int i = 0; i < 6; i++) {
                if(i == 0 || i == 5) {
                    NameResult strRes = parseName(index, response);
                    System.out.println("String field: " + strRes.name);
                    index = strRes.nextIndex;
                } else {
                    if(i == 3) {
                        NumberResult numberResult = parseUnsignedInt(index, 4, response);
                        System.out.println("Num field: " + numberResult.number);
                        index = numberResult.nextIndex;
                    } else {
                        NumberResult numberResult = parseUnsignedInt(index, 2, response);
                        System.out.println("Num field: " + numberResult.number);
                        index = numberResult.nextIndex;
                    }
                }
            }
        }

        System.out.println("Answer section [RFC 4.1.2. AR section format]");
        //alterations: ignore ipv6 address (type AAAA)
        //figure out how to parse 4 byte ipv4 address
        NameResult ipString = null;
        NameResult strRes = null;
        for(int count = 0; count < arCount; count++) {
            for(int i = 0; i < 6; i++) {
                if(i == 0) {
                    strRes = parseName(index, response);
                    System.out.println("String field: " + strRes.name);
                    index = strRes.nextIndex;
                } else if(i == 5) {
                    //NumberResult ipAddress = parseUnsignedInt(index, 4, response);
                    NameResult ipFound = parseAddress(index, response);
                    System.out.println("IP Address" + ipFound.name);
                    if(count == 0){ //first IP
                        ipString = ipFound;
                    }
                    index = ipFound.nextIndex;
                } else {
                    if(i == 3) {
                        NumberResult numberResult = parseUnsignedInt(index, 4, response);
                        System.out.println("Num field: " + numberResult.number);
                        index = numberResult.nextIndex;
                    } else {
                        NumberResult numberResult = parseUnsignedInt(index, 2, response);
                        System.out.println("Num field: " + numberResult.number);
                        index = numberResult.nextIndex;
                    }
                }
            }
        }
        return new NameResult[] {ipString, strRes}; //return the ip address
        //result = parseUnsignedInt(index, index, response);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: mydns domain-name root-dns-ip");
            System.exit(1);
        }
        
        String domainName = args[0]; //website to access
        String rootDnsIp = args[1]; //IP of WIDE root DNS server

        // Create UDP socket
        NameResult [] info = new NameResult[2];
        //{rootDnsIp, domainName};
        
        for(int i = 1;i < 5; i++){
            System.out.println("Starting a new Request! --====-=--=-==-=--=-=-=-=-=-=-=-==-=-=-=-=-");


        DatagramSocket socket = new DatagramSocket();
        // Send DNS query
        int id = i;

        if(i == 1) {
            byte[] query = createQuery(id, domainName);
            DatagramPacket packet = new DatagramPacket(query, query.length, 
                                        InetAddress.getByName(rootDnsIp), 53);
            socket.send(packet); //send it out for a response
        }else{
            byte[] query = createQuery(id, info[1].name);
            DatagramPacket packet = new DatagramPacket(query, query.length, 
                                    InetAddress.getByName(info[0].name), 53);
            socket.send(packet); //send it out for a response
        }
        //socket.send(packet); //send it out for a response
        System.out.println("Sent to: " + rootDnsIp);
        System.out.println("Sent packet -----------------------------------------------------");

        // Receive response
        byte[] response = new byte[2048];
        DatagramPacket responsePacket = new DatagramPacket(response, response.length);
        socket.receive(responsePacket); //get the socket's response and puts it into the packet
        System.out.println("Got response -----------------------------------------------------");

        // Parse response
        byte[] actualResponse = new byte[responsePacket.getLength()];
        System.arraycopy(response, 0, actualResponse, 0, responsePacket.getLength());
        info = parseResponse(actualResponse);
        rootDnsIp = info[0].name;
        System.out.println("Parsed response! -----------------------------------------------------");

        System.out.println("this response finished -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
        socket.close(); //close the socket
        }
        
        System.out.println("Final IP: " + rootDnsIp);
        /*
         * To do: 
         * Take those counts and parse all relevant names, name servers
         * Take all information and parse all relevant name, IP
         */
    }
}