#include <tins/tins.h>
#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <sys/types.h>
#include <ifaddrs.h>

using namespace std;
using namespace Tins;

//global vector for dns filtering
const static std::vector<std::string> domains = {"shodan", "google"};

std::set<std::string> int_names()
{
    ifaddrs *ifap;
    getifaddrs(&ifap); 

    std::set<std::string> interfaces = {};

    while (ifap->ifa_next != NULL) {
        interfaces.insert(ifap->ifa_name);
        ifap = ifap->ifa_next;
    }

    return interfaces;
}


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

    /*
    if(argc != 2) {
        std::cout << "Usage: " <<* argv << " <interface>" << std::endl;
        return 1; 
    }
    */
    std::set<string> interfaces = int_names();
    std::vector<string> int_vector;

    std::cout << "known network interfaces:" << std::endl;
    int i = 0;
    for (auto &name : interfaces) {
        int_vector.push_back(name);        
        std::cout << i << ": " << name << std::endl;
        i++;
    }
    
    char sel = {0};
    while (true) {
        std::string input = "";

        std::cout << "pick an interface: ";
        std::getline(cin, input);
        std::cout << std::endl;

        int char_val = input[0] - '0';

        if (input.length() == 1 && char_val <= int_vector.size()-1) {
            sel = input[0];
            break;
        }
        cout << "invalid input detected, please try again" << endl;
    }

    int sel_to_int = sel - '0'; 
    std::string interface = int_vector.at(sel_to_int);
 
    // Sniff on the provided interface in monitor mode
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    // Only capture udp packets sent to port 53
    config.set_filter("udp and dst port 53");
    Sniffer sniffer(interface, config);
    
    // Start the capture
    sniffer.sniff_loop(callback); 
}
