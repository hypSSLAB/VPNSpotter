#include "../include/core.h"
#include "../include/debug.h"
#include "../include/trace_parser.h"
#include "../include/vpn_fingerprint.h"

double calculate_permutation_entropy(uint8_t *sequence, int size, int order) {
    if (order < 2 || size < order) {
        fprintf(stderr, "Order must be at least 2 and size must be at least equal to order.\n");
        return -1.0;
    }

    int factorial = 1;
    for (int i = 2; i <= order; i++) {
        factorial *= i;
    }
    int num_patterns = factorial;

    int *pattern_counts = (int *)malloc(num_patterns * sizeof(int));
    if (!pattern_counts) {
        perror("Failed to allocate memory for pattern_counts");
        return -1.0;
    }

    for (int i = 0; i < num_patterns; i++) {
        pattern_counts[i] = 0;
    }

    int num_vectors = size - order + 1;

    uint8_t *subsequence = (uint8_t *)malloc(order * sizeof(uint8_t));
    int *indexes = (int *)malloc(order * sizeof(int));
    if (!subsequence || !indexes) {
        perror("Failed to allocate memory for temporary arrays");
        free(pattern_counts);
        if (subsequence) free(subsequence);
        if (indexes) free(indexes);
        return -1.0;
    }

    for (int i = 0; i < num_vectors; i++) {
        for (int j = 0; j < order; j++) {
            subsequence[j] = sequence[i + j];
            indexes[j] = j;
        }

        for (int j = 1; j < order; j++) {
            int key_index = indexes[j];
            uint8_t key_value = subsequence[key_index];
            int k = j - 1;
            while (k >= 0 && subsequence[indexes[k]] > key_value) {
                indexes[k + 1] = indexes[k];
                k--;
            }
            indexes[k + 1] = key_index;
        }

        int lehmer_code = 0;
        for (int j = 0; j < order; j++) {
            int cnt = 0;
            for (int k = j + 1; k < order; k++) {
                if (indexes[j] > indexes[k]) {
                    cnt++;
                }
            }
            lehmer_code = lehmer_code * (order - j) + cnt;
        }

        if (lehmer_code < 0 || lehmer_code >= num_patterns) {
            free(pattern_counts);
            free(subsequence);
            free(indexes);
            abort();
            return -1.0;
        }

        pattern_counts[lehmer_code]++;
    }

    double entropy = 0.0;
    int total_patterns = num_vectors;
    for (int i = 0; i < num_patterns; i++) {
        if (pattern_counts[i] > 0) {
            double p = (double)pattern_counts[i] / total_patterns;
            entropy -= p * log(p);
        }
    }

    entropy /= log(num_patterns);

    free(pattern_counts);
    free(subsequence);
    free(indexes);

    return entropy;
}

double calculate_shannon_entropy(uint8_t *sequence, int size) {
    if (size <= 0) {
        abort();
    }

    int frequencies[256];
    for (int i = 0; i < 256; i++) {
        frequencies[i] = 0;
    }

    for (int i = 0; i < size; i++) {
        frequencies[sequence[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            double p = (double)frequencies[i] / size;
            entropy -= p * log2(p);
        }
    }

    double max_entropy = log2(256);
    double normalized_entropy = entropy / max_entropy;

    return normalized_entropy;
}
