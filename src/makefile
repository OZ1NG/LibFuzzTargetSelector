#Makefile
CXX 	 = g++
CXXFLAGS = -no-pie
SRCS     = $(wildcard *.cpp)
OBJS     = $(SRCS:.c=.o)
TARGET   = lfts
LIBS	 = -lcapstone

all : $(TARGET)
	$(CXX) -o $(TARGET) $(OBJS) $(CXXFLAGS) $(LIBS) && rm -f *.o

$(TARGET) :
	$(CXX) -c $(SRCS)
 
clean :
	rm -f $(TARGET) *.o