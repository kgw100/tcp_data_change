#pragma once
#include <sfdafx.h>

void usage();
int cb(struct nfq_q_handle *q_handle, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data);
string replaceString(string subject, const string &search, const string &replace);
bool isvalid(const string &input);
