using Cake.Common.Build;
using Cake.Common.Diagnostics;
using Cake.Common.IO;
using Cake.Common.Solution;
using Cake.Common.Tools.DotNetCore;
using Cake.Common.Tools.DotNetCore.Build;
using Cake.Common.Tools.DotNetCore.Pack;
using Cake.Common.Tools.DotNetCore.Restore;
using Cake.Common.Tools.DotNetCore.Test;
using Cake.Common.Tools.NuGet;
using Cake.Common.Tools.NuGet.Push;
using Cake.Core;
using Cake.Core.Diagnostics;
using Cake.Core.IO;
using SimpleGitVersion;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using CK.Text;
using Cake.Common.Tools.NUnit;

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

            const string solutionName = "CK-AspNet-Auth";
            const string solutionFileName = solutionName + ".sln";
            var releasesDir = Cake.Directory( "CodeCakeBuilder/Releases" );

            var projects = Cake.ParseSolution( solutionFileName )
                           .Projects
                           .Where( p => !(p is SolutionFolder)
                                        && p.Name != "CodeCakeBuilder" );

            // We do not publish .Tests projects for this solution.
            var projectsToPublish = projects
                                        .Where( p => !p.Path.Segments.Contains( "Tests" ) );

            SimpleRepositoryInfo gitInfo = Cake.GetSimpleRepositoryInfo();

            // Configuration is either "Debug" or "Release".
            string configuration = "Debug";

            Task( "Check-Repository" )
                .Does( () =>
                 {
                     configuration = StandardCheckRepository( projectsToPublish, gitInfo );
                 } );

            Task( "Clean" )
                .IsDependentOn( "Check-Repository" )
                .Does( () =>
                 {
                     Cake.CleanDirectories( projects.Select( p => p.Path.GetDirectory().Combine( "bin" ) ) );
                     Cake.CleanDirectories( releasesDir );
                 } );


            Task( "Build" )
                .IsDependentOn( "Clean" )
                .IsDependentOn( "Check-Repository" )
                .Does( () =>
                 {
                     // Excludes WebApp from build since it relies on the auto generated assembly
                     // built by explicit test "GenerateStObjAssembly" below.
                     StandardSolutionBuild( solutionFileName, gitInfo, configuration, "WebApp" );
                 } );

            Task( "Unit-Testing" )
                .IsDependentOn( "Build" )
                .WithCriteria( () => !Cake.IsInteractiveMode()
                                        || Cake.ReadInteractiveOption( "Run unit tests?", 'Y', 'N' ) == 'Y' )
               .Does( () =>
                {
                    StandardUnitTests( configuration, projects
                                                        .Where( p => p.Name.EndsWith( ".Tests" )
                                                                     && !p.Path.Segments.Contains( "Integration" ) ) );
                } );

            Task( "Build-Integration-Projects" )
                .IsDependentOn( "Unit-Testing" )
                .Does( () =>
                {
                    // Use WebApp.Tests to generate the StObj assembly.
                    var webAppTests = projects.Single( p => p.Name == "WebApp.Tests" );
                    var path = webAppTests.Path.GetDirectory().CombineWithFilePath( "bin/" + configuration + "/net461/WebApp.Tests.dll" );
                    Cake.NUnit( path.FullPath, new NUnitSettings() { Include = "GenerateStObjAssembly" } );

                    var webApp = projects.Single( p => p.Name == "WebApp" );
                    Cake.DotNetCoreBuild( webApp.Path.FullPath,
                         new DotNetCoreBuildSettings().AddVersionArguments( gitInfo, s =>
                         {
                             s.Configuration = configuration;
                         } ) );
                } );

            Task( "Integration-Testing" )
                .IsDependentOn( "Build-Integration-Projects" )
                .WithCriteria( () => !Cake.IsInteractiveMode()
                                     || Cake.ReadInteractiveOption( "Run integration tests?", 'Y', 'N' ) == 'Y' )
                .Does( () =>
                {
                    var testProjects = projects
                                        .Where( p => p.Name.EndsWith( ".Tests" )
                                                    && p.Path.Segments.Contains( "Integration" ) );
                    StandardUnitTests( configuration, testProjects );
                } );


            Task( "Create-NuGet-Packages" )
                .WithCriteria( () => gitInfo.IsValid )
                .IsDependentOn( "Unit-Testing" )
                .IsDependentOn( "Integration-Testing" )
                .Does( () =>
                 {
                     StandardCreateNuGetPackages( releasesDir, projectsToPublish, gitInfo, configuration );
                 } );

            Task( "Push-NuGet-Packages" )
                .WithCriteria( () => gitInfo.IsValid )
                .IsDependentOn( "Create-NuGet-Packages" )
                .Does( () =>
                 {
                     IEnumerable<FilePath> nugetPackages = Cake.GetFiles( releasesDir.Path + "/*.nupkg" );
                     StandardPushNuGetPackages( nugetPackages, gitInfo );
                 } );

            // The Default task for this script can be set here.
            Task( "Default" )
                .IsDependentOn( "Push-NuGet-Packages" );

        }


    }
}
