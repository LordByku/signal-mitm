public class Main {
    public static void main(String[] args) {
    byte[] bytes = {10, 39, 10, 14, 102, 117, 99, 107, 32, 121, 111, 117, 32, 97, 108, 105, 99, 101, 50, 15, 98, 111, 98, 32, 112, 114, 111, 102, 105, 108, 101, 32, 107, 101, 121, 56, -29, -115, -102, -89, 6, -128};
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
        sb.append(String.format("%02X", b));
        }

    System.out.println(sb.toString());
    }
}
