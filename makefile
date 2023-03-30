#Makefile
CXX 	 = g++
CXXFLAGS = -no-pie -fPIC
SRCS     = $(wildcard src/*.cpp)
OBJS     = $(SRCS:.c=.o)
TARGET   = fts
LIBTARGET= libfts.so
LIBS	 = -lcapstone

all : $(TARGET)
	$(CXX) -o $(TARGET) $(OBJS) $(CXXFLAGS) $(LIBS) && rm -f *.o

$(TARGET) :
	$(CXX) -c $(SRCS)

libfts.so: src/fts.cpp
	$(CXX) $(CXXFLAGS) -shared -o $@ $^ && rm -f *.o

clean :
	rm -f $(TARGET) $(LIBTARGET) *.o
