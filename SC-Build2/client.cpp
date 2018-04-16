/*******************************************************************
 * Simple chat program (client side)
 *
 * Do not modify this file.
 *
 *******************************************************************/
 
#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>

#include "client-ws.h"
#include "common.h"
#include "common-ws.h"

using namespace std;

/*******************************************************************/
// Establish a TCP connection to IP <ip> at port <port>
//
// Returns -1 on error, otherwise the connection id

int ConnectToServer(char *ip, int port) {
    // setup a socket
    int server;
    if ((server = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        cout << "Could not create socket" << endl;
        return -1;
    }

    // connect to server
    struct sockaddr_in server_info;
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(port);
    
    if(inet_pton(AF_INET, ip, &server_info.sin_addr)<=0) // valid IP?
        return -1;

    if (connect(server,(struct sockaddr *)&server_info, sizeof(server_info)) != 0) 
        return -1;
    
    return server;
}


/*******************************************************************/
// Client-Server non-duplex messaging interface
//   any side can input # to end the chat

void StartChat(int server) {
    string msg;
    
    int buffer_size = 1024;
    byte buffer[buffer_size];
    
    while (true) {
        // get keyboard input and send to server
        cout << "\033[1;31mClient: \033[0m";
        getline(cin, msg);
        if (msg.length() == 0) msg.push_back(' ');
        
        if (EncryptAndSendMessage(server, (byte *)shared_key, (byte *)hmac_key,
                                  (byte *)msg.c_str(), msg.length()) == FAILURE) {
            cout << "\n[Unable to send message]" << endl;
            break;
        }
        if (msg.at(0) == '#') break; // client done
        
        // wait for server to say something 
        memset(buffer, 0, buffer_size); // zero-ing out receive buffer
        
        if (ReceiveAndDecryptMessage(server, (byte *)shared_key, (byte *)hmac_key, 
                                     buffer, buffer_size-1) == FAILURE) {
            cout << "\n[Unable to retrieve message]" << endl;
            break;
        }

        cout << "\033[1;33mServer: \033[0m" << buffer << endl;

        if (*buffer == '#') break; // server done            
    } 
}

/*******************************************************************/
// Main


int main()
{
    int port = 1234; // port number where server is listening 
    char server_ip[] = "127.0.0.1"; // server ip
    int server;
    
    // initialize openssl
    OpenSSLInit();

    // connect to server
    if ((server = ConnectToServer(server_ip,port)) == -1) { // error!
        cout << "[Unable to connect to " << server_ip << ":" << port << "]\n" << endl;
        exit(1);
    }
        
    // connected
    cout << "\n[Connected to " << server_ip << "]" << endl;

    // authenticate self (now moved to DHE procedure)
    if (AuthenticateToServer(server) == FAILURE) {
        cout << "\n[Client authentication failed]\n" << endl;
        exit(1);
    }
    cout << "\n[Client authenticated]\n" << endl;

    // ready to chat 
    cout << "Enter # to end chat\n" << endl;
    StartChat(server);

    // disconnect from server
    cout << "\n[Chat ended]\n" << endl;
    close(server);
    
    // cleanup openssl
    OpenSSLCleanup();

    return 0;
}
