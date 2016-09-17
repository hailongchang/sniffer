#include"GetOpt.h"
#include"string.h"

int optind = 1;
int optopt;					
char* optarg;

int paser_shotops(int argc,char *const argv[],
                  size_t length,char *item_cont,
                  const char *shortopts){
    
    const char *pos = NULL;                           
    if(length == 2 && item_cont[0] == '-'){
	pos = strchr(shortopts,item_cont[1]);
	if(NULL == pos){
	    optind++;                        
	    optopt = item_cont[1];
	    return '?';
	}else{
	    if(*(++pos) == ':'){   
		optarg = argv[++optind];
	    }
	    optind++;
	    return item_cont[1];
	}   
    }else{
	optopt = item_cont[0];
	optind = argc;
	return '?';
    }
}

int paser_longopts(int argc, char *const argv[],
		   size_t length,char *item_cont,
		   const char *shortopts,const struct option *longopts){
    
    char *assist_arg = NULL;       
    int long_index = 0;
    if( (length > 2) && (item_cont[0] == '-') && (item_cont[1] == '-')){
	while(longopts[long_index].name != NULL){
	    if(strcmp(item_cont+2,longopts[long_index].name) == 0){
		if(longopts[long_index].has_arg == required_argument)
		    optarg = argv[++optind];
		if(longopts[long_index].has_arg == optional_argument){
		    assist_arg = argv[optind + 1];
		    if(assist_arg[0] != '-'){
			optarg = assist_arg;
			++optind;
		    }
		}
		optopt = longopts[long_index].val;
		optind++;
		return optopt;
	    }else{
		long_index++;
	    }
	}
        optopt = item_cont[2];
        ++optind;
	return '?';
    }else{
	return paser_shotops(argc,argv,length,item_cont,shortopts);
    }
}

int getopt( int argc, char *const argv[], const char *shortopts ){   
    char *arg_item = NULL;
    size_t len = 0;
    if(argc == 1){
	return -1;
    }else{
	for(; optind < argc; optind++){
	    arg_item = argv[optind];
	    len = strlen(arg_item);

#ifndef CASE_SENSITIVE
	    arg_item = strlwr(arg_item);
#endif
	    return paser_shotops(argc,argv,len,arg_item,shortopts);
	}
        optind = 1;
	return -1;
    }
}

int getopt_long (int argc, char *const argv[],
		 const char *shortopts, const struct option *longopts, 
		 int *longind){

    char *pos = NULL;
    char *arg_item = NULL;
    size_t len = 0;
    if(argc == 1){
        return -1;
    }else{
        for(; optind < argc; optind++){
            arg_item = argv[optind];
	    len = strlen(arg_item);
	    
#ifndef CASE_SENSITIVE
	    arg_item = strlwr(arg_item);
#endif

	    *(arg_item+len) = 0;
	    return paser_longopts(argc,argv,len,arg_item,shortopts,longopts);
        }
	optind = 1;
	return -1;
    }
}
