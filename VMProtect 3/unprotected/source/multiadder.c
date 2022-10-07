int adder(int x, int y, int z) {
	y = z + y;
	x = x + y;
	return x;
}

int main(int argc, int** argv) {
	adder(20, 40, 60);
	return 0;
}