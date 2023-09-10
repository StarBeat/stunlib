
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

for _, filepath in ipairs(os.files("$(scriptdir)/test/*.c")) do
    print(filepath)
end

target("stun.test.testvector")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/testvector_test.c")
target_end()

target("stun.test.testvector_print")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/testvector_print_test.c")
target_end()

target("stun.test.realworldpackets")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/realworldpackets_test.c")
target_end()

target("stun.test.stunclient")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/stunclient_test.c")
target_end()

target("stun.test.turnmessage")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/turnmessage_test.c")
target_end()

target("stun.test.stunserver")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/stunserver_test.c")
target_end()

target("stun.test.turnclient")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/turnclient_test.c")
target_end()

target("stun.test.stuntrace")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/stuntrace_test.c")
target_end()

target("stun.test.crypto")
    set_kind("binary")
    
    set_group("stun.test")
    add_deps("stun")
    add_packages("xnet")
    
    add_includedirs("test")
    add_includedirs("include")
    add_files("test/test_utils.c")
    add_files("test/crypto_test.c")
target_end()
