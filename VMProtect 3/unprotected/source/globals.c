int test1 = 0xDEADBEEF;
int test2 = 0xC0FFEEBABE;

int globalAccess() {
	test2 = test1;
	test1 = 0xBEEEEEEF;
}

int main(int argc, int** argv) {
	globalAccess();
	return 0;
}