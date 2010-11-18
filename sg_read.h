#ifndef _SG_READ_H
int sg_is_sg(const char * filename);
int sg_rw(int sg_fd, int rw, unsigned char * buff, int blocks,
                    int64_t from_block, int bs, int cdbsz,
                    int fua, int dpo, int * diop, int do_mmap,
                    int no_dxfer);
int64_t sg_getsize(int sg_fd);
#endif // _SG_READ_H
