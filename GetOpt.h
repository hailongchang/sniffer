#define     no_argument         0
#define     required_argument   1
#define     optional_argument   2
#define     CASE_SENSITIVE


#ifdef __cplusplus
extern"C" {
#endif
    extern int optind;               //再次再次调用 getopt() 时的下一个 argv 指针的索引
    extern int optopt;               //最后一个已知选项
    extern char* optarg;             //指向当前选项参数（如果有）的指针

    extern int getopt( int argc, char *const argv[], const char *shortopts);

#ifdef __cplusplus
}
#endif


#ifdef __cplusplus
extern"C" {
#endif
    struct option{
	char *name;                  //指向长选项名称的指针   
	int has_arg;                 //表示选项是否有参数
	int *flag;               
	int val;                     //表示选项的短参数
    };

    extern int getopt_long (int argc, 
			    char *const argv[],
			    const char *shortopts, 
			    const struct option *longopts, 
			    int *longind);
#ifdef __cplusplus
}
#endif

