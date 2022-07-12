

int test(int a, int b, int c) {
    return (a + b) * c;
}

void test2(char *buf, int x) {
    for (int i = 0; i < x; ++i) {
        buf[i] = buf[i] * 100;
    }
}

int main() {
    test(1,2,3);

    char *data = "hello world";
    test2(data, 10);
}
