#define     no_argument         0
#define     required_argument   1
#define     optional_argument   2
#define     CASE_SENSITIVE


#ifdef __cplusplus
extern"C" {
#endif
    extern int optind;               //�ٴ��ٴε��� getopt() ʱ����һ�� argv ָ�������
    extern int optopt;               //���һ����֪ѡ��
    extern char* optarg;             //ָ��ǰѡ�����������У���ָ��

    extern int getopt( int argc, char *const argv[], const char *shortopts);

#ifdef __cplusplus
}
#endif


#ifdef __cplusplus
extern"C" {
#endif
    struct option{
	char *name;                  //ָ��ѡ�����Ƶ�ָ��   
	int has_arg;                 //��ʾѡ���Ƿ��в���
	int *flag;               
	int val;                     //��ʾѡ��Ķ̲���
    };

    extern int getopt_long (int argc, 
			    char *const argv[],
			    const char *shortopts, 
			    const struct option *longopts, 
			    int *longind);
#ifdef __cplusplus
}
#endif

