#include <iostream>

class Hello
{
public:
	Hello(const char* msg)
		: msg_(msg)
	{
	}
	void run()
	{
		std::cout << msg_ << std::endl;
	}
	const char* msg_;
};

int main(int argc, char** argv)
{
	Hello h("Hello World");
	h.run();
}
