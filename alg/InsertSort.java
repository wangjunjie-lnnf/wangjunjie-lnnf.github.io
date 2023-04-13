package alg;

public class InsertSort {
    
    public static void main(String[] args) {
        int[] arr = new int[] { 4, 7, 1, 9, 3, 6 };
        
        insertSort(arr);

        for (int i = 0; i < arr.length; i++) {
            System.out.println(arr[i]);
        }
    }

    static void insertSort(int[] arr) {
        int n = arr.length;
        for (int i = 1; i < n; i++) {
            // 把i插入[0, i)中
            int ele = arr[i];
            int j = i - 1;
            
            while (j >= 0) {
                // 找到第一个比ele小的位置
                if (arr[j] < ele) {
                    break;
                }
    
                arr[j+1] = arr[j];
                j--;
            }
            arr[j + 1] = ele;
        }
    }

}
