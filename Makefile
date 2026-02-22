all: run

clean:
	rm -f out/HashCracker.jar

out/HashCracker.jar: out/parcs.jar src/HashCracker.java
	@mkdir -p temp
	@javac -cp out/parcs.jar -d temp src/HashCracker.java
	@jar cf out/HashCracker.jar -C temp .
	@rm -rf temp/

build: out/HashCracker.jar