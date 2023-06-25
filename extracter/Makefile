

CXX = g++
LD = g++

SRCS = $(wildcard *.cpp)

OBJS = $(patsubst %cpp, %o, $(SRCS))

CXXFLAGS = -g -ldwarf -fsanitize=leak

TARGET = extracter

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) -o $@ $^ -ldwarf

%.o:%.cpp
	$(CXX) -c $^ $(CXXFLAGS) -I./thirdparty/nlohmann

clean:
	rm -f $(OBJS) $(TARGET)
