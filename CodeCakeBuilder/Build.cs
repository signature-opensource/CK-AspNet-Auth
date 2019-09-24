using Cake.Common.IO;
using Cake.Common.Tools.DotNetCore;
using Cake.Common.Tools.DotNetCore.Build;
using Cake.Common.Tools.NUnit;
using Cake.Core;
using Cake.Core.Diagnostics;
using SimpleGitVersion;
using System;
using System.Linq;

namespace CodeCake
{
    /// <summary>
    /// Standard build "script".
    /// </summary>
    [AddPath( "%UserProfile%/.nuget/packages/**/tools*" )]
    public partial class Build : CodeCakeHost
    {
        public Build()
        {
            Cake.Log.Verbosity = Verbosity.Diagnostic;

            SimpleRepositoryInfo gitInfo = Cake.GetSimpleRepositoryInfo();
            StandardGlobalInfo globalInfo = CreateStandardGlobalInfo( gitInfo )
                                                .AddDotnet()
                                                .AddNPM()
                                                .SetCIBuildTag();

            Task( "Check-Repository" )
                .Does( () =>
                {
                    globalInfo.TerminateIfShouldStop();
                } );

            Task( "Clean" )
                .IsDependentOn( "Check-Repository" )
                .Does( () =>
                 {
                     globalInfo.GetDotnetSolution().Clean();
                     Cake.CleanDirectories( globalInfo.ReleasesFolder );
                     globalInfo.GetNPMSolution().Clean();
                 } );


            Task( "Build" )
                .IsDependentOn( "Check-Repository" )
                .IsDependentOn( "Clean" )
                .Does( () =>
                 {
                     globalInfo.GetDotnetSolution().Build();
                     globalInfo.GetNPMSolution().Build();
                 } );

            Task( "Unit-Testing" )
                .IsDependentOn( "Build" )
                .WithCriteria( () => Cake.InteractiveMode() == InteractiveMode.NoInteraction
                                     || Cake.ReadInteractiveOption( "RunUnitTests", "Run Unit Tests?", 'Y', 'N' ) == 'Y' )
               .Does( () =>
                {
                    var testProjects = globalInfo.GetDotnetSolution().Projects.Where( p => p.Name.EndsWith( ".Tests" )
                                                            && !p.Path.Segments.Contains( "Integration" ) );

                    globalInfo.GetDotnetSolution().Test(testProjects);
                    globalInfo.GetNPMSolution().Test();
                } );

            Task( "Build-Integration-Projects" )
                .IsDependentOn( "Unit-Testing" )
                .Does( () =>
                {
                    // Use WebApp.Tests to generate the StObj assembly.
                    var webAppTests = globalInfo.GetDotnetSolution().Projects.Single( p => p.Name == "WebApp.Tests" );
                    var path = webAppTests.Path.GetDirectory().CombineWithFilePath( "bin/" + globalInfo.BuildConfiguration + "/net461/WebApp.Tests.dll" );
                    Cake.NUnit3( path.FullPath, new NUnit3Settings{ Test = "WebApp.Tests.DBSetup.Generate_StObj_Assembly_Generated" } );
                    var webApp = globalInfo.GetDotnetSolution().Projects.Single( p => p.Name == "WebApp" );
                    Cake.DotNetCoreBuild( webApp.Path.FullPath,
                         new DotNetCoreBuildSettings().AddVersionArguments( gitInfo, s =>
                         {
                             s.Configuration = globalInfo.BuildConfiguration;
                         } ) );
                } );

            Task( "Integration-Testing" )
                .IsDependentOn( "Build-Integration-Projects" )
                .WithCriteria( () => Cake.InteractiveMode() == InteractiveMode.NoInteraction
                                     || Cake.ReadInteractiveOption( "Run integration tests?", 'N', 'Y' ) == 'Y' )
                .Does( () =>
                {
                    var testIntegrationProjects = globalInfo.GetDotnetSolution().Projects
                                                    .Where( p => p.Name.EndsWith( ".Tests" )
                                                                 && p.Path.Segments.Contains( "Integration" ) );
                    globalInfo.GetDotnetSolution().Test( testIntegrationProjects );
                } );


            Task( "Create-Packages" )
                .WithCriteria( () => gitInfo.IsValid )
                .IsDependentOn( "Unit-Testing" )
                .IsDependentOn( "Integration-Testing" )
                .Does( () =>
                 {
                     globalInfo.GetDotnetSolution().Pack();
                     globalInfo.GetNPMSolution().RunPack();
                 } );

            Task( "Push-Packages" )
                .WithCriteria( () => gitInfo.IsValid )
                .IsDependentOn( "Create-Packages" )
                .Does( () =>
                 {
                     globalInfo.PushArtifacts();
                 } );

            // The Default task for this script can be set here.
            Task( "Default" )
                .IsDependentOn( "Push-Packages" );

        }


    }
}
