

#ifndef ANTIVIRUS_REPORT_H
#define ANTIVIRUS_REPORT_H

#ifndef REPORT_H
#define REPORT_H

#include <stdio.h>

// Called before a new scan starts
void report_start(const char *path);

// Adds one file's result (called from scanner)
void report_add_result(const char *file, const char *hash, int infected, int suspicious, double ai_score, double entropy);

// Called after scan is done (saves JSON to file)
void report_finish(int total, int infected, double seconds, const char *filename);

#endif






#endif //ANTIVIRUS_REPORT_H