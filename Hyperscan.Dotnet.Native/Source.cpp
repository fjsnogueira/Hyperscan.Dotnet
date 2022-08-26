/*
 * Copyright (c) 2015-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <hs/hs.h>

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::vector;

// Match event handler: called every time Hyperscan finds a match.
static
int onMatch(unsigned int id, unsigned long long from, unsigned long long to,
    unsigned int flags, void* ctx) {
    // Our context points to a size_t storing the match count
    int* matchedId = (int*)ctx;
    (*matchedId) = id;
    return 0;
}

// Class wrapping all state associated with the hyperscan engine
class HyperscanEngine {
private:
    // Hyperscan compiled database
    hs_database_t* db;

    // Hyperscan temporary scratch space (used in both modes)
    hs_scratch_t* scratch;

public:
    HyperscanEngine() : db(nullptr), scratch(nullptr) {}

    HyperscanEngine(hs_database_t* database)
        : db(database), scratch(nullptr) {
        // Allocate enough scratch space to handle block
        // mode, so we only need the one scratch region.
        hs_error_t err = hs_alloc_scratch(db, &scratch);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: could not allocate scratch space. Exiting." << endl;
            exit(-1);
        }
    }

    ~HyperscanEngine() {
        // Free scratch region
        hs_free_scratch(scratch);
        // Close Hyperscan databases
        hs_free_database(db);
    }

    void set_database(hs_database_t* database) {
        db = database;
        // Allocate enough scratch space to handle block
        // mode, so we only need the one scratch region.
        hs_error_t err = hs_alloc_scratch(db, &scratch);
        if (err != HS_SUCCESS) {
            cerr << "ERROR: could not allocate scratch space. Exiting." << endl;
            exit(-1);
        }
    }

    hs_database_t* get_database() {
        return db;
    }

    hs_scratch_t* get_scratch() {
        return scratch;
    }
};

extern "C" __declspec(dllexport) HyperscanEngine * create_hyperscan_engine();
extern "C" __declspec(dllexport) void compile_block_db(HyperscanEngine * engine, const char* pattern_file);
extern "C" __declspec(dllexport) int scan_single(HyperscanEngine * engine, const char* data);
extern "C" __declspec(dllexport) void clean(HyperscanEngine * engine);

// helper function - see end of file
static void parseFile(const char* filename, vector<string>& patterns,
    vector<unsigned>& flags, vector<unsigned>& ids);

static hs_database_t* buildDatabase(const vector<const char*>& expressions,
    const vector<unsigned> flags,
    const vector<unsigned> ids,
    unsigned int mode) {
    hs_database_t* db;
    hs_compile_error_t* compileErr;
    hs_error_t err;

    err = hs_compile_multi(expressions.data(), flags.data(), ids.data(),
        expressions.size(), mode, nullptr, &db, &compileErr);

    if (err != HS_SUCCESS) {
        if (compileErr->expression < 0) {
            // The error does not refer to a particular expression.
            cerr << "ERROR: " << compileErr->message << endl;
        }
        else {
            cerr << "ERROR: Pattern '" << expressions[compileErr->expression]
                << "' failed compilation with error: " << compileErr->message
                << endl;
        }
        // As the compileErr pointer points to dynamically allocated memory, if
        // we get an error, we must be sure to release it. This is not
        // necessary when no error is detected.
        hs_free_compile_error(compileErr);
        exit(-1);
    }
    return db;
}

HyperscanEngine* create_hyperscan_engine() {
    return new HyperscanEngine();
}

void compile_block_db(HyperscanEngine* engine, const char* pattern_file) {
    // hs_compile_multi requires three parallel arrays containing the patterns,
    // flags and ids that we want to work with. To achieve this we use
    // vectors and new entries onto each for each valid line of input from
    // the pattern file.
    vector<string> patterns;
    vector<unsigned> flags;
    vector<unsigned> ids;

    // do the actual file reading and string handling
    parseFile(pattern_file, patterns, flags, ids);

    // Turn our vector of strings into a vector of char*'s to pass in to
    // hs_compile_multi. (This is just using the vector of strings as dynamic
    // storage.)
    vector<const char*> cstrPatterns;
    for (const auto& pattern : patterns) {
        cstrPatterns.push_back(pattern.c_str());
    }

    hs_database_t* db = buildDatabase(cstrPatterns, flags, ids, HS_MODE_BLOCK);

    // set database and allocate scratch space
    engine->set_database(db);
}

int scan_single(HyperscanEngine* engine, const char* data) {

    if (data == nullptr || engine == nullptr || engine->get_database() == nullptr) {
        cerr << "ERROR: No input file or no Hyperscan engine has been compiled." << endl;
        exit(-1);
    }

    int matchId = -1;
    const std::string& in = data;
    hs_error_t err = hs_scan(engine->get_database(), in.c_str(), in.length(), 0,
        engine->get_scratch(), onMatch, &matchId);

    if (err != HS_SUCCESS) {
        cerr << "ERROR: Unable to scan data. Exiting." << endl;
        exit(-1);
    }

    return matchId;
}

void clean(HyperscanEngine* engine) {
    delete engine;
}

static unsigned parseFlags(const string& flagsStr) {
    unsigned flags = 0;
    for (const auto& c : flagsStr) {
        switch (c) {
        case 'i':
            flags |= HS_FLAG_CASELESS; break;
        case 'm':
            flags |= HS_FLAG_MULTILINE; break;
        case 's':
            flags |= HS_FLAG_DOTALL; break;
        case 'H':
            flags |= HS_FLAG_SINGLEMATCH; break;
        case 'V':
            flags |= HS_FLAG_ALLOWEMPTY; break;
        case '8':
            flags |= HS_FLAG_UTF8; break;
        case 'W':
            flags |= HS_FLAG_UCP; break;
        case '\r': // stray carriage-return
            break;
        default:
            cerr << "Unsupported flag \'" << c << "\'" << endl;
            exit(-1);
        }
    }
    return flags;
}

static void parseFile(const char* filename, vector<string>& patterns,
    vector<unsigned>& flags, vector<unsigned>& ids) {
    ifstream inFile(filename);
    if (!inFile.good()) {
        cerr << "ERROR: Can't open pattern file \"" << filename << "\"" << endl;
        exit(-1);
    }

    for (unsigned i = 1; !inFile.eof(); ++i) {
        string line;
        getline(inFile, line);

        // if line is empty, or a comment, we can skip it
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // otherwise, it should be ID:PCRE, e.g.
        //  10001:/foobar/is

        size_t colonIdx = line.find_first_of(':');
        if (colonIdx == string::npos) {
            cerr << "ERROR: Could not parse line " << i << endl;
            exit(-1);
        }

        // we should have an unsigned int as an ID, before the colon
        unsigned id = std::stoi(line.substr(0, colonIdx).c_str());

        // rest of the expression is the PCRE
        const string expr(line.substr(colonIdx + 1));

        size_t flagsStart = expr.find_last_of('/');
        if (flagsStart == string::npos) {
            cerr << "ERROR: no trailing '/' char" << endl;
            exit(-1);
        }

        string pcre(expr.substr(1, flagsStart - 1));
        string flagsStr(expr.substr(flagsStart + 1, expr.size() - flagsStart));
        unsigned flag = parseFlags(flagsStr);

        patterns.push_back(pcre);
        flags.push_back(flag);
        ids.push_back(id);
    }
}