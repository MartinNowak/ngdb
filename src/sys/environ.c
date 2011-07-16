extern char** environ;

char** getEnviron() { return environ; }
void setEnviron(char** env) { environ = env; }
