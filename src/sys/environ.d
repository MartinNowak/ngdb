module sys.environ;

extern(C) char** getEnviron();
extern(C) void setEnviron(char**);

alias getEnviron environ;
alias setEnviron environ;
