obj = spawn.o
all : spawn 
.PHONY : all

spawn : $(obj)
	cc -o spawn $(obj)

.PHONY : clean
clean :
	rm spawn $(obj)
