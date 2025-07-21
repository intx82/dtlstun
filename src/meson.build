project('dtlstun', 'cpp', default_options : ['cpp_std=c++20', 'warning_level=3'])

openssl_dep = dependency('openssl', required : true)
thread_dep  = dependency('threads')
spdlog_dep  = dependency('spdlog', required : true, default_options : ['header_only=true'])

src = [ 'main.cpp', 'arg_parse.cpp', 'routing.cpp']
inc = include_directories('.')

add_project_arguments('-g3',  language : 'cpp')
add_project_arguments('-g3',  language : 'c')

executable('dtlstun',
           src,
           include_directories : inc,
           dependencies        : [openssl_dep, thread_dep, spdlog_dep],
           install             : true
)

# test('run-help', executable('dtlstun'), args : ['--help'])
