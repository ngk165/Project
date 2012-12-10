COMPILER	= g++
FLAGS	 	= 
LIBRARIES	= -l ssl -l crypto

all: ServerF/ssl_server.cpp ClientF/ssl_client.cpp
	$(COMPILER) $(FLAGS) -o ServerF/server ServerF/ssl_server.cpp $(LIBRARIES)
	$(COMPILER) $(FLAGS) -o ClientF/client ClientF/ssl_client.cpp $(LIBRARIES)
