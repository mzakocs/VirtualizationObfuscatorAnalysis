int virtFunction2() {
	return 0xDEADBEEF;
}

int virtFunction1() {
	int test = virtFunction2();
	return test;
}

int main(int argc, int** argv) {
	virtFunction2();
	return virtFunction1();
}