#include <tins/tins.h>
#include <iostream>
#include <vector>
#include <string>

using namespace std;
using namespace Tins;

std::vector<std::string> domains = {"shodan", "google"};

bool callback(const PDU& pdu)
{
    DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
    
    for (const auto& query : dns.queries()) {
        std::string dname = query.dname();
        for (auto &domain : domains) {
            std::size_t found = dname.find(domain);
            if (found < 1000){
                std::cout << dname << std::endl;
            }
            found = 0;
        }
    }
    return true;
}



int main(int argc, char* argv[])
{
    if(argc != 2) {
        std::cout << "Usage: " <<* argv << " <interface>" << std::endl;
        return 1;
    }
    // Sniff on the provided interface in promiscuos mode
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    // Only capture udp packets sent to port 53
    config.set_filter("udp and dst port 53");
    Sniffer sniffer(argv[1], config);
    
    // Start the capture
    sniffer.sniff_loop(callback);
}
