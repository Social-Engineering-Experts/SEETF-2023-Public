FOPT = -ffast-math # -fwhole-program

GENPROFILE = g++ -O3 \
		-fprofile-generate \
		$(FOPT) \
		-s -DNDEBUG \
		-I. chal.c -lcurses -lm

build-release:
	$(GENPROFILE)
	cat profiling_input | ./a.out

	g++ -O3 \
		-fprofile-use -fbranch-probabilities -fvpt \
		$(FOPT) \
		-s -DNDEBUG \
		-ffunction-sections -fdata-sections \
		-I. chal.c -lcurses -lm -Wl,--gc-sections

	cp a.out ../dist/cubeland
	cp preview.JPG ../dist/bro.jpg

build-debug:
	$(GENPROFILE)
	cat profiling_input | ./a.out

	g++ -O3 \
		-fprofile-use -fbranch-probabilities -fvpt \
		$(FOPT) \
		-I. chal.c -lcurses -lm

build:
	g++ -O3 \
		$(FOPT) \
		-I. chal.c -lcurses -lm