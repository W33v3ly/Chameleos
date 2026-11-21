
    for (int i = 0; i < pack_count; i++) free(ps[i].data);
    free(ps); free(packed_idx); free(is_packed); free(new_off);
    free(stub); free(mstub); free(blob); free(sled); free(fd); free(out);
    return 0;
}
