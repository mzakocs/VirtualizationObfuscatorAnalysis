
int ptr_drf(__int64* test) {
	__int64 yo = *test;
	return 0xDEADBEEF;
}

int main(int argc, int** argv) {
	__int64 wow = 0xC0FFEE;
	return ptr_drf(&wow);
}