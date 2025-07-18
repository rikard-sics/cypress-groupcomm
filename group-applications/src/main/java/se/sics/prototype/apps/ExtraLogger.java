/*******************************************************************************
 * Copyright (c) 2025, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.prototype.apps;

/**
 * Handles printing of extra log messages.
 *
 */
public class ExtraLogger {

	private static boolean loggingEnabled = true;

	/**
	 * Print a logging message
	 * 
	 * @param type the type
	 * @param priority the priority
	 * @param category the category
	 * @param message the message
	 * @param device the name of the device sending the log message
	 * 
	 */
	static public void printLog(String type, String priority, String category, String device, String message) {

		// Return if logging is not enabled
		if (!loggingEnabled) {
			return;
		}

		// Print information about message to be logged
		message = device + ": " + message;
		System.out.format("[LOG] \"%s\" (Type: %s, Priority: %s, Category: %s)%n", message, type, priority, category);

	}

	/**
	 * Enable or disable extra logging
	 * 
	 * @param logging true/false
	 */
	static public void setLogging(boolean logging) {
		loggingEnabled = logging;
	}

	public static class Const {

	    /**
		 * Enums for logging levels
		 */
	    public static String TYPE_INFO = "info";
	    public static String TYPE_WARNING = "warning";
	    public static String TYPE_ERROR = "error";
	    public static String PRIO_LOW = "low";
	    public static String PRIO_MEDIUM = "medium";
	    public static String PRIO_HIGH = "high";
	    public static String CAT_STATUS = "status";
	    public static String DEVICE_NAME = "ACE Resource Server";
	}

}

