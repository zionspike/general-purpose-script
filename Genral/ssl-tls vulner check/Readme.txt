##############################################################################
#     KKKKKKKKK    KKKKKKK                                        iiii       #
#     K:::::::K    K:::::K                                       i::::i      #
#     K:::::::K    K:::::K                                        iiii       #
#     K:::::::K   K::::::K                                                   #
#     KK::::::K  K:::::KKK  aaaaaaaaaaaaa   ppppp   ppppppppp   iiiiiii      #
#       K:::::K K:::::K     a::::::::::::a  p::::ppp:::::::::p  i:::::i      #
#       K::::::K:::::K      aaaaaaaaa:::::a p:::::::::::::::::p  i::::i      #
#       K:::::::::::K                a::::a pp::::::ppppp::::::p i::::i      #
#       K:::::::::::K         aaaaaaa:::::a  p:::::p     p:::::p i::::i      #
#       K::::::K:::::K      aa::::::::::::a  p:::::p     p:::::p i::::i      #
#       K:::::K K:::::K    a::::aaaa::::::a  p:::::p     p:::::p i::::i      #
#     KK::::::K  K:::::KKKa::::a    a:::::a  p:::::p    p::::::p i::::i      #
#     K:::::::K   K::::::Ka::::a    a:::::a  p:::::ppppp:::::::pi::::::i     #
#     K:::::::K    K:::::Ka:::::aaaa::::::a  p::::::::::::::::p i::::::i     #
#     K:::::::K    K:::::K a::::::::::aa:::a p::::::::::::::pp  i::::::i     #
#     KKKKKKKKK    KKKKKKK  aaaaaaaaaa  aaaa p::::::pppppppp    iiiiiiii     #
#                                            p:::::p                         #
#                                            p:::::p                         #
#                                           p:::::::p                        #
#                                           p:::::::p                        #
#                                           p:::::::p                        #
#                                           ppppppppp                        #
#   <SSL/TLS Vulnerabilities Tester v1.0>                                    #
#     ------------------------------------------------------------------     #
#   This script is for testing the following SSL/TLS vulnerabilities:        #
#                                                                            #
#          - BEAST                                                           #
#          - CRIME                                                           #
#          - POODLE                                                          #
#          - HEARTBLEED                                                      #
#       - usage: SSL-TLS-Kapi.py <host> <port>                               #
##############################################################################

	This script is to check vulnerabilities of HTTP over SSL/TLS by involving result of TestSSLServer.jar
, Nmap and sslyze.exe recommended by OWASP.
	
	***This script has a bug in testing on localhost because of failure of Nmap.