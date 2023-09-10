
if is_plat("windows") then 
    add_cflags("/W3")
    if is_mode("debug") then 
        set_symbols("debug")
    end
elseif is_plat("linux") then 
    add_cflags("-std=gnu99", "-Wall", "-Wextra", "-pedantic")
    add_cflags("-Wno-gnu-zero-variadic-macro-arguments")
    add_defines("CTEST_SEGFAULT")
end 

set_optimize("fast")

add_requires("xnet")

target("stun")
    set_kind("shared")

    add_packages("xnet")
    add_includedirs("include")
    add_headerfiles("include/**.h")
    add_files("src/**.c")
