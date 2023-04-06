package alg;

public class BinarySearch {
    
    public static void main(String[] args) {
        int[] arr = new int[] { 1,3,4,6,7,9 };
        int index = binarySearch(arr, 6);
        System.out.println(index);
    }

    static int binarySearch(int[] arr, int key) {

        int low = 0;
        int hi = arr.length;

        while (low < hi) {
            int mid = (low + hi) / 2;
            if (arr[mid] > key) {
                hi = mid - 1;
            } else if (arr[mid] < key) {
                low = mid + 1;
            } else {
                return mid;
            }
        }

        if (arr[low] == key) {
            return low;
        }

        return -1;
    }

}
