#include "ssl.h"
using namespace Tins;

int main(int argc, char** argv) {
    if(argc != 2) {
        exit(0);
    }
    SnifferConfiguration config;    
    config.set_filter("dst port 443");
    config.set_immediate_mode(true);
    NetworkInterface::Info info(NetworkInterface(argv[1]).addresses());
    Sniffer sniffer(argv[1],config);
    Packet pk;

    PDU *pdu = nullptr;
    TCP *tcp = NULL;        
    while (true) {
        pk = sniffer.next_packet();        
        pdu = pk.pdu();     
        tcp = pdu->find_pdu<TCP>();
        if (!tcp) continue;
        if(!tcp->find_pdu<RawPDU>()) continue;        
        TLS b(tcp->find_pdu<RawPDU>()->serialize());                
        if(b.handshake.type.num != Htype_t::CLIENT_HELLO) continue;     
        std::string server_name =  b.handshake.Extensions.server_names();
        if(server_name.empty()){
            continue;
        }
        std::cout << server_name << std::endl;
    }
}

