//File: ServerMain.java
//Purpose: Main class for Server SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date:10/11/2020

import java.io.*;
import java.net.*;

public class ServerMain {
    public static void main(String[] args){

        //test server socket stuff
        try {
            ServerSocket sSocket = new ServerSocket(6969);
            Socket sClientSocket = sSocket.accept();
            PrintWriter out = new PrintWriter(sClientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(sClientSocket.getInputStream()));

            String input, output;
            out.println("Connection established");
            input = in.readLine();
            out.println("Server ECHO: " + input);

        }
        catch(IOException e){
            System.out.println("IOException in server main: " + e.getMessage());
        }
        catch(Exception e){
            System.out.println("Exception in server main: " + e.getMessage());
        }
    }


}
