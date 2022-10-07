
int switchFunc (int i) {
    switch (i) {
        case 1:
            return 20;
            break;
        case 2:
            return 42;
            break;
        case 3:
            return 54;
            break;
        case 4:
            return i;
            break;
        case 5:
            return 93;
            break;
        case 6:
            return 321;
            break;
    }
    return 0;
}

int main(int argc, char** argv) {
    switchFunc(4);
    return 0;
}