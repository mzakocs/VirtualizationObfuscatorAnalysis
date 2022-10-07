void cpuid_test() {
	int cpuInfo[4];

	// CPUID without ECX
	__cpuid(cpuInfo, 1);

	// CPUID with ECX
	__cpuidex(cpuInfo, 7, 0);
}


int main(int argc, char** argv) {
	cpuid_test();
	return 0;
}