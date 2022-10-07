
int arithmetic(int x, int y) {
	int test = x;
	int test2 = y;
	test = test ^ test2;
	test = test & test2;
	test = test | test2;
	return test;
}

int main(int argc, int** argv) {
	arithmetic(20, 40);
	return 0;
}