#include <util.h>
#include <sfdafx.h>


void usage() {
  printf("syntax: tcp_data_change <from string> <to string> \n");
  printf("sample: tcp_data_change hacking Hooking \n");
}
// return replaced string
string replaceString(string subject, const string &search, const string &replace)
{
    size_t pos = 0;
    if (!isvalid(search) || !isvalid((replace))) return "";
    else {
        while((pos = subject.find(search, pos)) != string::npos)
        {
            subject.replace(pos, search.length(), replace);
            pos += replace.length();
        }
        return subject;
    }
}
//unsigned char * replaceString (u_char & data ,const char * fr_str,const char * to_str)
//{
//    char * pos;
//    while((pos=strstr((char *)data,fr_str))!= NULL)
//    {
//            strncpy(ptr,to_str,to)
//    }

//}

bool isvalid(const string &input){
    if (input.empty()) return false;
    for (int i = 0; i < input.size(); ++i){
        char ch = input[i];
        if ( !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) ) return false;
    }
    return true;
}
