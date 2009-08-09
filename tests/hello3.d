version(LDC) {
    import std.compat;
}
import std.stdio;

class Hello
{
    this(string msg)
    {
	msg_ = msg;
    }
    void run()
    {
	writefln("%s", msg_);
    }
    string msg_;
}

void main(string[] args)
{
    auto h = new Hello("Hello World");
    h.run();
}
