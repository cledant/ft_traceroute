cmake_minimum_required(VERSION 3.10)
project(ft_traceroute)

#Setup binary compilation
add_executable(ft_traceroute
		srcs/ft_traceroute.c
		srcs/opt.c
		srcs/utility_network.c
		srcs/loop.c
		srcs/header.c
		srcs/utility.c
		srcs/display.c
		srcs/checksum.c
		srcs/socket.c
		srcs/process_response.c)
target_include_directories(ft_traceroute PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/includes)
target_compile_options(ft_traceroute PRIVATE -Wall -Wextra -Werror -std=gnu11 -march=native -flto)
target_link_libraries(ft_traceroute m)