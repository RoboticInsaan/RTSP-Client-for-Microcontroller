#include <iostream>
#include <cstring>
#include <string>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "md5.h"

#define BUF_LEN 1024
#define MD5_DIGEST_LENGTH 	32
#define MD5_BUF_SIZE 	(MD5_SIZE + sizeof('\0'))

std::string control;
std::string realm;
std::string nonce;
std::string sessionId;
time_t starttime;
int seq = 1;

std::string defaultServerIp = "192.168.1.4";
int defaultServerPort = 1935;
std::string defaultTestUri = "/video.mp4";
std::string defaultUserAgent = "RTSP Client";
std::string defaultUsername = "admin";
std::string defaultPassword = "Embedded@";

std::string genmsg_DESCRIBE(const std::string& url, int seq, const std::string& userAgent, const std::string& authSeq) {
    std::string msgRet = "DESCRIBE " + url + " RTSP/1.0\r\n";
    msgRet += "CSeq: " + std::to_string(seq) + "\r\n";
    msgRet += "Authorization: " + authSeq + "\r\n";
    msgRet += "User-Agent: " + userAgent + "\r\n";
    msgRet += "Accept: application/sdp\r\n";
    msgRet += "\r\n";
    return msgRet;
}

std::string genmsg_SETUP(const std::string& url, int seq, const std::string& userAgent, const std::string& authSeq) {
    std::string msgRet = "SETUP " + url + " RTSP/1.0\r\n";
    msgRet += "CSeq: " + std::to_string(seq) + "\r\n";
    msgRet += "Authorization: " + authSeq + "\r\n";
    msgRet += "User-Agent: " + userAgent + "\r\n";
    msgRet += "Blocksize: 65535\r\n";
    msgRet += "Transport: RTP/AVP/TCP;unicast\r\n";
    msgRet += "\r\n";
    return msgRet;
}

std::string genmsg_OPTIONS(const std::string& url, int seq, const std::string& userAgent, const std::string& sessionId, const std::string& authSeq) {
    std::string msgRet = "OPTIONS " + url + " RTSP/1.0\r\n";
    msgRet += "CSeq: " + std::to_string(seq) + "\r\n";
    msgRet += "User-Agent: " + userAgent + "\r\n";
    msgRet += "Session: " + sessionId + "\r\n";
    msgRet += "\r\n";
    return msgRet;
}

std::string genmsg_PLAY(const std::string& url, int seq, const std::string& userAgent, const std::string& sessionId, const std::string& authSeq) {
    std::string msgRet = "PLAY " + url + " RTSP/1.0\r\n";
    msgRet += "CSeq: " + std::to_string(seq) + "\r\n";
    msgRet += "User-Agent: " + userAgent + "\r\n";
    msgRet += "Session: " + sessionId + "\r\n";
    msgRet += "Range: npt=0.000-\r\n";
    msgRet += "\r\n";
    return msgRet;
}

std::string genmsg_TEARDOWN(const std::string& url, int seq, const std::string& userAgent, const std::string& sessionId, const std::string& authSeq) {
    std::string msgRet = "TEARDOWN " + url + " RTSP/1.0\r\n";
    msgRet += "CSeq: " + std::to_string(seq) + "\r\n";
    msgRet += "User-Agent: " + userAgent + "\r\n";
    msgRet += "Session: " + sessionId + "\r\n";
    msgRet += "\r\n";
    return msgRet;
}

std::string decodeControl(const std::string& bytesContent) {
    std::string mapRetInf;
    size_t pos = bytesContent.find("rtsp");
    if (pos != std::string::npos) {
        mapRetInf = bytesContent.substr(pos);
    }
    return mapRetInf;
}

std::string decodeSession(const std::string& strContent) {
    std::string mapRetInf;
    size_t pos = strContent.find("Session");
    if (pos != std::string::npos) {
        size_t a = strContent.find(":", pos);
        size_t b = strContent.find(";", a);
        mapRetInf = strContent.substr(a + 2, b - a - 2);
    }
    return mapRetInf;
}

// Implement other genmsg_ functions similarly

std::string generateAuthString(const std::string& username, const std::string& password, const std::string& realm,
                                const std::string& method, const std::string& uri, const std::string& nonce) {
    std::string combined_str1 = username + ":" + realm + ":" + password;
    std::string combined_str2 = method + ":" + uri;

    MD5_CTX context;
    MD5Init(&context);
    MD5Update(&context, reinterpret_cast<unsigned char*>(const_cast<char*>(combined_str1.c_str())), combined_str1.length());
    unsigned char m1[MD5_DIGEST_LENGTH];
    MD5Final(&context, m1);

    MD5Init(&context);
    MD5Update(&context, reinterpret_cast<unsigned char*>(const_cast<char*>(combined_str2.c_str())), combined_str2.length());
    unsigned char m2[MD5_DIGEST_LENGTH];
    MD5Final(&context, m2);

    std::string combined_str3 = bin2hex(m1, MD5_DIGEST_LENGTH) + ":" + nonce + ":" + bin2hex(m2, MD5_DIGEST_LENGTH);

    MD5Init(&context);
    MD5Update(&context, reinterpret_cast<unsigned char*>(const_cast<char*>(combined_str3.c_str())), combined_str3.length());
    unsigned char response[MD5_DIGEST_LENGTH];
    MD5Final(&context, response);

    std::stringstream mapRetInf;
    mapRetInf << "Digest ";
    mapRetInf << "username=\"" << defaultUsername << "\", ";
    mapRetInf << "realm=\"" << realm << "\", ";
    mapRetInf << "algorithm=\"MD5\", ";
    mapRetInf << "nonce=\"" << nonce << "\", ";
    mapRetInf << "uri=\"" << uri << "\", ";
    mapRetInf << "response=\"" << bin2hex(response, MD5_DIGEST_LENGTH) << "\"";

    return mapRetInf.str();
}


std::string bin2hex(const unsigned char* data, int length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return ss.str();
}
void sendAndReceive(const std::string& message, int& seq, int& sockfd) {
    send(sockfd, message.c_str(), message.length(), 0);

    char buffer[BUF_LEN];
    recv(sockfd, buffer, BUF_LEN, 0);
    std::cout << buffer << std::endl;

    seq++;
}

void setup() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error opening socket");
        return;
    }
    else {
      Serial.println("ok\n");
    }
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(defaultServerPort);
    inet_pton(AF_INET, defaultServerIp.c_str(), &serverAddress.sin_addr);

    
    if (connect(sockfd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == 0) {
            Serial.println("sync connect success");

        } else if (errno == EINPROGRESS){
            Serial.println("async connecting...");        
    }
        else {
            Serial.println("invalid connect");
            return;
        }
    std::string url = "rtsp://" + defaultServerIp + defaultTestUri;
    char buffer[BUF_LEN];
    bool isDigest = false;
std::string authSeq = "Basic " + std::string("YWRtaW46RW1iZWRkZWRA");

    sendAndReceive(genmsg_DESCRIBE(url, seq, defaultUserAgent, authSeq), seq, sockfd);

    char* unauthorizedCheck = strstr(buffer, "Unauthorized");
    if (unauthorizedCheck > 0) {
        isDigest = true;

        // New DESCRIBE with digest authentication
        char* start = strstr(buffer, "realm");
        char* begin = strchr(start, '\"');
        char* end = strchr(begin + 1, '\"');
        std::string realm(begin + 1, end);

        start = strstr(buffer, "nonce");
        begin = strchr(start, '\"');
        end = strchr(begin + 1, '\"');
        std::string nonce(begin + 1, end);

        authSeq = generateAuthString(defaultUsername, defaultPassword, realm, "DESCRIBE", defaultTestUri, nonce);

        sendAndReceive(genmsg_DESCRIBE(url, seq, defaultUserAgent, authSeq), seq, sockfd);
    }

    control = decodeControl(buffer);

    if (isDigest) {
        authSeq = generateAuthString(defaultUsername, defaultPassword, realm, "SETUP", defaultTestUri, nonce);
    }

    sendAndReceive(genmsg_SETUP(control, seq, defaultUserAgent, authSeq), seq, sockfd);

    char sessionIdBuffer[BUF_LEN];
    recv(sockfd, sessionIdBuffer, BUF_LEN, 0);
    sessionId = decodeSession(sessionIdBuffer);

    sendAndReceive(genmsg_OPTIONS(url, seq, defaultUserAgent, sessionId, authSeq), seq, sockfd);

    char optionsBuffer[BUF_LEN];
    recv(sockfd, optionsBuffer, BUF_LEN, 0);
    std::cout << optionsBuffer << std::endl;

    seq++;

    sendAndReceive(genmsg_PLAY(url + "/", seq, defaultUserAgent, sessionId, authSeq), seq, sockfd);

    char playBuffer[BUF_LEN];
    recv(sockfd, playBuffer, BUF_LEN, 0);
    std::cout << playBuffer << std::endl;

    seq++;

    starttime = time(nullptr);

    while (true) {
        // Send a new RTSP OPTION command to keep the stream alive
        time_t now = time(nullptr);
        if (difftime(now, starttime) > 50) {
            sendAndReceive(genmsg_OPTIONS(url, seq, defaultUserAgent, sessionId, authSeq), seq, sockfd);
            starttime = time(nullptr);
        }

        char msgRcvBuffer[BUF_LEN];
        recv(sockfd, msgRcvBuffer, BUF_LEN, 0);
    }

    seq++;

    sendAndReceive(genmsg_TEARDOWN(url, seq, defaultUserAgent, sessionId, authSeq), seq, sockfd);

    char teardownBuffer[BUF_LEN];
    recv(sockfd, teardownBuffer, BUF_LEN, 0);
    std::cout << teardownBuffer << std::endl;

    close(sockfd);


}

void loop() {
    

}