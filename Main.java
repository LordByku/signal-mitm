public class Main {
    public static void main(String[] args) {
    byte[] bytes = {5, 44, -7, -23, 68, -89, -80, -61, -70, 114, -122, -79, 126, -128, 55, 76, -74, 26, 61, 124, 124, 43, 26, -41, 104, -16, 57, 123, 107, -57, -38, 15, 7};
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
        sb.append(String.format("%02X", b));
        }

    System.out.println(sb.toString());
    }
}