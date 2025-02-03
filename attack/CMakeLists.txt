cmake_minimum_required(VERSION 3.5.0)
project(attack VERSION 0.1.0 LANGUAGES C)

add_executable(attack aes.c haraka.c precalc.c run.c)

