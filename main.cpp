#include "./ssl.h"
using namespace Tins;

int main() {
    std::stringstream ss;
    ss<<std::hex;
    
    SnifferConfiguration config;    
    config.set_filter("dst port 443");
    config.set_immediate_mode(true);
    NetworkInterface::Info info(NetworkInterface("wlp2s0").addresses());
    Sniffer sniffer("wlp2s0",config);
    Packet pk;

    PDU *pdu = nullptr;
    TCP *tcp = NULL;        
    std::vector<std::string> v;   
    while (true) {
        pk = sniffer.next_packet();        
        pdu = pk.pdu();     
        tcp = pdu->find_pdu<TCP>();
        if (!tcp) continue;
        if(!tcp->find_pdu<RawPDU>()) continue;        
        TLS b(tcp->find_pdu<RawPDU>()->serialize());                
        if(b.handshake.type.num != Htype_t::CLIENT_HELLO) continue;                     
        v.push_back(b.handshake.Extensions.server_names());
        for(auto i : v) {
            ss<<i<<std::endl;
        }
        // ss << std::hex << std::setfill('0') << std::setw(4) <<static_cast<int>(b.handshake.Ctype.byte)<<std::endl;        
        // int j = 0;        
        // for(auto i : b.handshake.Extensions.bytes) {            
        //     j++;
        //     ss<< std::setfill('0') << std::setw(2) << static_cast<int>(i) << " ";                            
        //     if(j%16 == 0) ss << std::endl;
        //     else if(j%8 == 0) ss<<"| ";            
        // }
        
        std::cout<<ss.str()<<std::endl<<"======================== ========================"<<std::endl;
        ss.str("");       
    }
}
