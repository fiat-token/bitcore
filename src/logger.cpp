#include <fstream>
#include <string>

class Logger
{
    private:
        // std::string logFile = "logkal.log";
        std::string logFile;
        
    public:
        Logger() {};
        Logger(std::string file) : logFile(file) {};

        bool write(std::string data)
        {
            const char * c = "logkal.log";
            std::ofstream outfile;
            outfile.open(c, std::ios_base::app);
            if(!outfile.is_open()) return false;
            outfile << data << "\n";
            return true;
        }

        bool write(unsigned char& data)
        {
            const char * c = "logkal.log";
            std::ofstream outfile;
            outfile.open(c, std::ios_base::app);
            if(!outfile.is_open()) return false;
            outfile << data << "\n";
            return true;
        }
};