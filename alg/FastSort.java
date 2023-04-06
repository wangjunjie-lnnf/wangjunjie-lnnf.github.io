package alg;

public class FastSort {
    
    public static void main(String[] args) {
        int[] arr = new int[] { 4, 7, 1, 9, 3, 6 };
        fastSort(arr, 0, arr.length - 1);

        for (int i = 0; i < arr.length; i++) {
            System.out.println(arr[i]);
        }
    }
    
    static void fastSort(int[] arr, int low, int hi) {
        if (low >= hi) {
            return;
        }

        int origLow = low;
        int origHi = hi;
    
        // 任选一个元素作为分割点
        int ele = arr[low];
        // 分割点已保存，可以被覆盖
        int blank = low;
    
        while (low < hi) {
            // 先从右边找一个小的挪到左边
            while (low < hi) {
                if (arr[hi] < ele) {
                    arr[blank] = arr[hi];
                    blank = hi;
                    break;
                }
                hi--;
            }
    
            // 再从左边找一个大的挪到右边
            while (low < hi) {
                if (arr[low] > ele) {
                    arr[blank] = arr[low];
                    blank = low;
                    break;
                }
                low++;
            }
        }
    
        arr[blank] = ele;
    
        fastSort(arr, origLow, blank - 1);
        fastSort(arr, blank + 1, origHi);
    }

}
